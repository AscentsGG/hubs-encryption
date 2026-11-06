//! Live interop with the TypeScript implementation: every test runs
//! `tests/ts-mls-peer.mts` (the TypeScript implementation on ts-mls) as a
//! separate Node process and plays the native side through the core's
//! public interface, in both directions.
//!
//! Needs Node 24 and the TypeScript package with its dependencies installed
//! (`npm ci` in `typescript/` at the root of this repository). Set
//! HUBS_TYPESCRIPT_DIR to the package's folder to use one somewhere else,
//! and HUBS_NODE to pick a node binary. Set HUBS_SKIP_LIVE_TS_MLS=1 to skip
//! these tests on a machine without Node.

use std::{
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use hubs_mls::*;
use serde_json::{json, Value};

/// The TypeScript package's folder: HUBS_TYPESCRIPT_DIR, or `typescript/`
/// at the root of this repository.
fn typescript_dir() -> PathBuf {
    let dir = std::env::var_os("HUBS_TYPESCRIPT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../typescript"));
    std::fs::canonicalize(&dir)
        .ok()
        .filter(|dir| dir.join("package.json").is_file())
        .unwrap_or_else(|| {
            panic!(
                "no TypeScript package at {} (set HUBS_TYPESCRIPT_DIR, or HUBS_SKIP_LIVE_TS_MLS=1 to skip)",
                dir.display()
            )
        })
}

/// `node --import tsx` for one of the scripts in this folder, run from the
/// TypeScript package's folder so Node finds tsx and ts-mls there.
fn node_script(script: &str) -> Command {
    let dir = typescript_dir();
    let node = std::env::var("HUBS_NODE").unwrap_or_else(|_| "node".into());
    let mut command = Command::new(node);
    command
        .current_dir(&dir)
        .env("HUBS_TYPESCRIPT_DIR", &dir)
        .args(["--import", "tsx"])
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join(script),
        );
    command
}

struct Peer {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Peer {
    fn start() -> Option<Peer> {
        if std::env::var_os("HUBS_SKIP_LIVE_TS_MLS").is_some() {
            eprintln!("skipping the live ts-mls test (HUBS_SKIP_LIVE_TS_MLS)");
            return None;
        }
        let mut child = node_script("ts-mls-peer.mts")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start node (set HUBS_NODE, or HUBS_SKIP_LIVE_TS_MLS=1 to skip)");
        let stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut ready = String::new();
        stdout.read_line(&mut ready).unwrap();
        assert!(
            ready.contains("ready"),
            "the ts-mls peer did not start: {ready}"
        );
        Some(Peer {
            child,
            stdin,
            stdout,
        })
    }

    fn try_call(&mut self, request: Value) -> Result<Value, String> {
        // Node's readline also ends lines at U+2028 and U+2029; escape them.
        let line = request
            .to_string()
            .replace('\u{2028}', "\\u2028")
            .replace('\u{2029}', "\\u2029");
        writeln!(self.stdin, "{line}").unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        let reply: Value =
            serde_json::from_str(&line).unwrap_or_else(|_| panic!("peer said {line:?}"));
        if reply["ok"] == true {
            Ok(reply)
        } else {
            Err(reply["error"].as_str().unwrap_or("?").to_owned())
        }
    }

    fn call(&mut self, request: Value) -> Value {
        let op = request["op"].clone();
        self.try_call(request)
            .unwrap_or_else(|e| panic!("ts-mls {op}: {e}"))
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn hx(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex string")).expect("hex")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn native(user_id: &str) -> (IdentityKeys, Arc<MlsDevice>) {
    let identity = create_identity().unwrap();
    let keys = create_device(identity.clone(), user_id.into(), new_device_id().unwrap()).unwrap();
    (identity, MlsDevice::new(keys).unwrap())
}

fn second_device(identity: &IdentityKeys, user_id: &str) -> Arc<MlsDevice> {
    MlsDevice::new(
        create_device(identity.clone(), user_id.into(), new_device_id().unwrap()).unwrap(),
    )
    .unwrap()
}

fn draft(id: &str, body: &str) -> MessageDraft {
    MessageDraft {
        id: id.into(),
        kind: "text".into(),
        body: body.into(),
        sent_at: 1_760_000_000_000,
        expires_in_seconds: 604_800,
    }
}

fn opened(incoming: Incoming) -> (MessagePayload, GroupMember) {
    match incoming {
        Incoming::Message {
            payload, sender, ..
        } => (payload, sender),
        other => panic!("expected a message, got {other:?}"),
    }
}

fn change_epoch(incoming: Incoming) -> u64 {
    match incoming {
        Incoming::Change { epoch, .. } => epoch,
        other => panic!("expected a change, got {other:?}"),
    }
}

fn web_send(peer: &mut Peer, name: &str, id: &str, body: &str) -> Value {
    peer.call(
        json!({"op": "send", "name": name, "id": id, "body": body, "sentAt": 1_760_000_000_000i64}),
    )
}

/// The TypeScript side reads a native message and checks the franking
/// commitment and the sender itself (its `receive`); this checks it read
/// the right thing.
fn web_reads(peer: &mut Peer, name: &str, sent: &EncryptedMessage, from: &Arc<MlsDevice>) {
    let read =
        peer.call(json!({"op": "receive", "name": name, "message": hex::encode(&sent.ciphertext)}));
    assert_eq!(read["kind"], "message");
    assert_eq!(read["payload"]["body"], sent.payload.body.as_str());
    assert_eq!(read["sender"]["deviceId"], from.device_id().as_str());
    assert_eq!(hx(&read["commitment"]), sent.commitment);
}

#[test]
fn the_web_starts_and_adds_phones() {
    let Some(mut peer) = Peer::start() else {
        return;
    };
    let now = now();
    let conversation = "3f1e2d4c-5b6a-4789-8a0b-1c2d3e4f5a6b";
    peer.call(
        json!({"op": "device", "name": "alice", "userId": "u_alice", "deviceId": "alice_web_1"}),
    );
    peer.call(json!({"op": "start", "name": "alice", "conversationId": conversation}));

    let (bob_identity, bob) = native("u_bob");
    let packages = bob.create_key_packages(2, now).unwrap();
    // ts-mls reads what the core made, lifetime included.
    let lifetime = peer
        .call(json!({"op": "lifetime", "keyPackage": hex::encode(&packages[0].public_package)}));
    assert_eq!(
        lifetime["notAfter"],
        (now + KEY_PACKAGE_LIFETIME_SECONDS).to_string()
    );
    let added = peer.call(
        json!({"op": "change", "name": "alice", "add": [hex::encode(&packages[0].public_package)]}),
    );
    assert_eq!(added["epoch"], 0);
    let b1 = bob
        .join_from_welcome(
            hx(&added["welcome"]),
            packages[0].clone(),
            conversation.into(),
        )
        .unwrap();
    assert_eq!(b1.epoch(), 1);
    assert_eq!(b1.members().len(), 2);

    // Web to phone, phone to web.
    let m1 = web_send(&mut peer, "alice", "m_1", "Hello from the web.");
    let (payload, sender) = opened(b1.receive(hx(&m1["ciphertext"])).unwrap());
    assert_eq!(payload.body, "Hello from the web.");
    assert_eq!(sender.device_id, "alice_web_1");
    let reply = b1
        .encrypt_message(draft("m_2", "Hello from the phone."))
        .unwrap();
    web_reads(&mut peer, "alice", &reply, &bob);

    // The phone's weekly refresh, then the web's, each followed by a message.
    let update = b1.change_devices(vec![], vec![], now, None).unwrap();
    b1.merge_pending_commit().unwrap();
    let applied = peer
        .call(json!({"op": "receive", "name": "alice", "message": hex::encode(&update.commit)}));
    assert_eq!(applied["kind"], "change");
    assert_eq!(applied["epoch"], 2);
    let after = b1
        .encrypt_message(draft("m_3", "After my refresh."))
        .unwrap();
    web_reads(&mut peer, "alice", &after, &bob);
    let web_update = peer.call(json!({"op": "change", "name": "alice"}));
    assert_eq!(
        change_epoch(b1.receive(hx(&web_update["commit"])).unwrap()),
        3
    );
    let m4 = web_send(&mut peer, "alice", "m_4", "After the web's refresh.");
    assert_eq!(
        opened(b1.receive(hx(&m4["ciphertext"])).unwrap()).0.body,
        "After the web's refresh."
    );

    // Bob sets up a second phone; the web adds it. The first phone applies
    // the commit, the second joins from the welcome.
    let bob2 = second_device(&bob_identity, "u_bob");
    let package2 = bob2.create_key_packages(1, now).unwrap().remove(0);
    let added2 = peer.call(
        json!({"op": "change", "name": "alice", "add": [hex::encode(&package2.public_package)]}),
    );
    match b1.receive(hx(&added2["commit"])).unwrap() {
        Incoming::Change { members, epoch, .. } => {
            assert_eq!(epoch, 4);
            assert_eq!(members.len(), 3);
        }
        other => panic!("{other:?}"),
    }
    let b2 = bob2
        .join_from_welcome(hx(&added2["welcome"]), package2, conversation.into())
        .unwrap();
    assert_eq!(b2.epoch(), 4);
    let m5 = web_send(&mut peer, "alice", "m_5", "Both phones read this.");
    assert_eq!(
        opened(b1.receive(hx(&m5["ciphertext"])).unwrap()).0.body,
        "Both phones read this."
    );
    assert_eq!(
        opened(b2.receive(hx(&m5["ciphertext"])).unwrap()).0.body,
        "Both phones read this."
    );
    let from_b2 = b2
        .encrypt_message(draft("m_6", "From the second phone."))
        .unwrap();
    web_reads(&mut peer, "alice", &from_b2, &bob2);
    assert_eq!(
        opened(b1.receive(from_b2.ciphertext.clone()).unwrap())
            .0
            .body,
        "From the second phone."
    );

    // The web retires the second phone: the first applies it, the second is out.
    let leaf = b1
        .members()
        .iter()
        .find(|m| m.device_id == bob2.device_id())
        .unwrap()
        .leaf_index;
    let removed = peer.call(json!({"op": "change", "name": "alice", "removeLeaves": [leaf]}));
    assert_eq!(change_epoch(b1.receive(hx(&removed["commit"])).unwrap()), 5);
    assert_eq!(b1.members().len(), 2);
    assert!(matches!(
        b2.receive(hx(&removed["commit"])).unwrap(),
        Incoming::Removed { .. }
    ));
    let m7 = web_send(&mut peer, "alice", "m_7", "Only one phone now.");
    assert_eq!(
        opened(b1.receive(hx(&m7["ciphertext"])).unwrap()).0.body,
        "Only one phone now."
    );
    assert!(b2.receive(hx(&m7["ciphertext"])).is_err());
}

#[test]
fn a_phone_starts_and_adds_web_devices() {
    let Some(mut peer) = Peer::start() else {
        return;
    };
    let now = now();
    let conversation = "8d7c6b5a-4f3e-4d2c-9b1a-0f9e8d7c6b5a";
    let (_, alice) = native("u_alice");
    let a = alice.start_group(conversation.into(), now).unwrap();

    peer.call(json!({"op": "device", "name": "bob", "userId": "u_bob", "deviceId": "bob_web_1"}));
    let made = peer.call(json!({"op": "keyPackages", "name": "bob", "count": 2}));
    let package = &made["packages"][0];
    let change = a
        .change_devices(vec![hx(&package["hex"])], vec![], now, None)
        .unwrap();
    assert_eq!(change.added[0].device_id, "bob_web_1");
    assert_eq!(change.epoch, 0);
    a.merge_pending_commit().unwrap();
    let joined = peer.call(json!({"op": "join", "name": "bob", "welcome": hex::encode(change.welcome.as_ref().unwrap()), "keyPackageId": package["id"]}));
    assert_eq!(joined["conversationId"], conversation);
    assert_eq!(joined["epoch"], 1);
    assert_eq!(joined["members"].as_array().unwrap().len(), 2);

    let hello = a
        .encrypt_message(draft("m_1", "Hello from the phone."))
        .unwrap();
    web_reads(&mut peer, "bob", &hello, &alice);
    let back = web_send(&mut peer, "bob", "m_2", "Hello from the web.");
    let (payload, sender) = opened(a.receive(hx(&back["ciphertext"])).unwrap());
    assert_eq!(payload.body, "Hello from the web.");
    assert_eq!(sender.user_id, "u_bob");

    let web_update = peer.call(json!({"op": "change", "name": "bob"}));
    assert_eq!(
        change_epoch(a.receive(hx(&web_update["commit"])).unwrap()),
        2
    );

    // Bob links a second web device; the phone adds it.
    peer.call(json!({"op": "device", "name": "bob2", "userId": "u_bob", "deviceId": "bob_web_2", "identityOf": "bob"}));
    let made2 = peer.call(json!({"op": "keyPackages", "name": "bob2", "count": 1}));
    let package2 = &made2["packages"][0];
    let change2 = a
        .change_devices(vec![hx(&package2["hex"])], vec![], now, None)
        .unwrap();
    a.merge_pending_commit().unwrap();
    let seen =
        peer.call(json!({"op": "receive", "name": "bob", "message": hex::encode(&change2.commit)}));
    assert_eq!(seen["members"].as_array().unwrap().len(), 3);
    let joined2 = peer.call(json!({"op": "join", "name": "bob2", "welcome": hex::encode(change2.welcome.as_ref().unwrap()), "keyPackageId": package2["id"]}));
    assert_eq!(joined2["epoch"], 3);
    let both = a
        .encrypt_message(draft("m_3", "Both web devices read this."))
        .unwrap();
    web_reads(&mut peer, "bob", &both, &alice);
    web_reads(&mut peer, "bob2", &both, &alice);

    // The phone retires the second web device.
    let leaf = a
        .members()
        .iter()
        .find(|m| m.device_id == "bob_web_2")
        .unwrap()
        .leaf_index;
    let removal = a.change_devices(vec![], vec![leaf], now, None).unwrap();
    a.merge_pending_commit().unwrap();
    let seen =
        peer.call(json!({"op": "receive", "name": "bob", "message": hex::encode(&removal.commit)}));
    assert_eq!(seen["members"].as_array().unwrap().len(), 2);
    let last = a
        .encrypt_message(draft("m_4", "Just the first web device."))
        .unwrap();
    web_reads(&mut peer, "bob", &last, &alice);
    let last_back = web_send(&mut peer, "bob", "m_5", "Still here.");
    assert_eq!(
        opened(a.receive(hx(&last_back["ciphertext"])).unwrap())
            .0
            .body,
        "Still here."
    );
}

#[test]
fn json_escapes_match_the_web() {
    let Some(mut peer) = Peer::start() else {
        return;
    };
    let now = now();
    let conversation = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
    peer.call(json!({"op": "device", "name": "web", "userId": "u_web", "deviceId": "web_1"}));
    peer.call(json!({"op": "start", "name": "web", "conversationId": conversation}));
    let (_, phone) = native("u_phone");
    let package = phone.create_key_packages(1, now).unwrap().remove(0);
    let added = peer.call(
        json!({"op": "change", "name": "web", "add": [hex::encode(&package.public_package)]}),
    );
    let group = phone
        .join_from_welcome(hx(&added["welcome"]), package, conversation.into())
        .unwrap();

    let bodies = [
        "Tab\t, newline\n, return\r, quote \", backslash \\, slash /, </script>",
        "\u{0}\u{1}\u{8}\u{b}\u{c}\u{1f}\u{7f} control characters",
        "emoji 🗂️ and 👩🏽‍💻 and flags 🇺🇸",
        "\u{2028}\u{2029} line and paragraph separators",
        "accents déjà vu, 日本語, العربية",
        "",
    ];
    for (i, body) in bodies.iter().enumerate() {
        // The same bytes on both sides for the same payload.
        let payload = MessagePayload {
            id: format!("m_{i}"),
            kind: "text".into(),
            body: (*body).into(),
            sent_at: 1_760_000_000_123,
            expires_in_seconds: 3_600,
            user_id: "u_web".into(),
            device_id: "web_1".into(),
            franking_key: vec![7; 32],
        };
        let web = peer.call(json!({"op": "canonical", "payload": {
            "id": payload.id, "kind": payload.kind, "body": payload.body, "sentAt": payload.sent_at,
            "expiresInSeconds": payload.expires_in_seconds, "userId": payload.user_id,
            "deviceId": payload.device_id, "frankingKey": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
        }}));
        assert_eq!(
            hx(&web["hex"]),
            canonical_payload_bytes(payload.clone()),
            "canonical bytes for {body:?}"
        );
        assert_eq!(
            web["json"].as_str().unwrap().as_bytes(),
            payload_json(payload).as_slice(),
            "payload JSON for {body:?}"
        );
        // And through MLS both ways (an empty text is for the app to refuse, not MLS).
        let sent = web_send(&mut peer, "web", &format!("w_{i}"), body);
        assert_eq!(
            opened(group.receive(hx(&sent["ciphertext"])).unwrap())
                .0
                .body,
            *body
        );
        let mine = group
            .encrypt_message(draft(&format!("p_{i}"), body))
            .unwrap();
        web_reads(&mut peer, "web", &mine, &phone);
    }
}

#[test]
fn late_and_out_of_order_messages_open() {
    let Some(mut peer) = Peer::start() else {
        return;
    };
    let now = now();
    let conversation = "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b";
    peer.call(json!({"op": "device", "name": "web", "userId": "u_web", "deviceId": "web_1"}));
    peer.call(json!({"op": "start", "name": "web", "conversationId": conversation}));
    let (_, phone) = native("u_phone");
    let package = phone.create_key_packages(1, now).unwrap().remove(0);
    let added = peer.call(
        json!({"op": "change", "name": "web", "add": [hex::encode(&package.public_package)]}),
    );
    let group = phone
        .join_from_welcome(hx(&added["welcome"]), package, conversation.into())
        .unwrap();

    let m1 = web_send(&mut peer, "web", "m_1", "one");
    let m2 = web_send(&mut peer, "web", "m_2", "two");
    let m3 = web_send(&mut peer, "web", "m_3", "three");
    // Delivered three, one, two.
    assert_eq!(
        opened(group.receive(hx(&m3["ciphertext"])).unwrap()).0.body,
        "three"
    );
    assert_eq!(
        opened(group.receive(hx(&m1["ciphertext"])).unwrap()).0.body,
        "one"
    );
    assert_eq!(
        opened(group.receive(hx(&m2["ciphertext"])).unwrap()).0.body,
        "two"
    );

    // A message from the epoch before a commit, delivered after it.
    let late = web_send(&mut peer, "web", "m_4", "sent before the refresh");
    let refresh = peer.call(json!({"op": "change", "name": "web"}));
    change_epoch(group.receive(hx(&refresh["commit"])).unwrap());
    assert_eq!(
        opened(group.receive(hx(&late["ciphertext"])).unwrap())
            .0
            .body,
        "sent before the refresh"
    );

    // And the same after a save and reload in between.
    let late2 = web_send(&mut peer, "web", "m_5", "late again");
    let refresh2 = peer.call(json!({"op": "change", "name": "web"}));
    change_epoch(group.receive(hx(&refresh2["commit"])).unwrap());
    let saved = group.snapshot().unwrap();
    let reloaded = phone.load_group(saved).unwrap();
    assert_eq!(
        opened(reloaded.receive(hx(&late2["ciphertext"])).unwrap())
            .0
            .body,
        "late again"
    );
}

#[test]
fn the_epoch_race_with_the_web() {
    let Some(mut peer) = Peer::start() else {
        return;
    };
    let now = now();
    let conversation = "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e";
    peer.call(json!({"op": "device", "name": "web", "userId": "u_web", "deviceId": "web_1"}));
    peer.call(json!({"op": "start", "name": "web", "conversationId": conversation}));
    let (_, phone) = native("u_phone");
    let package = phone.create_key_packages(1, now).unwrap().remove(0);
    let added = peer.call(
        json!({"op": "change", "name": "web", "add": [hex::encode(&package.public_package)]}),
    );
    let group = phone
        .join_from_welcome(hx(&added["welcome"]), package, conversation.into())
        .unwrap();

    // Both commit from epoch 1; the server takes the web's first, so the
    // phone's comes back EPOCH_CHANGED: clear, catch up, commit again.
    let mine = group.change_devices(vec![], vec![], now, None).unwrap();
    let theirs = peer.call(json!({"op": "change", "name": "web"}));
    assert_eq!(theirs["epoch"], mine.epoch);
    group.clear_pending_commit();
    assert_eq!(
        change_epoch(group.receive(hx(&theirs["commit"])).unwrap()),
        2
    );
    let again = group.change_devices(vec![], vec![], now, None).unwrap();
    assert_eq!(again.epoch, 2);
    group.merge_pending_commit().unwrap();
    let applied =
        peer.call(json!({"op": "receive", "name": "web", "message": hex::encode(&again.commit)}));
    assert_eq!(applied["epoch"], 3);
    let after = group
        .encrypt_message(draft("m_1", "after the race"))
        .unwrap();
    web_reads(&mut peer, "web", &after, &phone);
}

#[test]
fn forged_web_devices_are_refused() {
    let Some(mut peer) = Peer::start() else {
        return;
    };
    let now = now();
    let (_, alice) = native("u_alice");
    let a = alice
        .start_group("4d5e6f7a-8b9c-4d0e-9f1a-2b3c4d5e6f7a".into(), now)
        .unwrap();
    peer.call(json!({"op": "device", "name": "bob", "userId": "u_bob", "deviceId": "bob_web_1"}));
    // Mallory's device claims Bob's identity key with a certificate from another key.
    peer.call(json!({"op": "device", "name": "mallory", "userId": "u_bob", "deviceId": "bob_web_9", "identityOf": "bob", "forgeWith": true}));
    let forged = peer.call(json!({"op": "keyPackages", "name": "mallory", "count": 1}));
    let error = a
        .change_devices(vec![hx(&forged["packages"][0]["hex"])], vec![], now, None)
        .unwrap_err();
    assert!(
        matches!(error, HubsMlsError::Credential { .. }),
        "{error:?}"
    );
    // Nothing was staged.
    assert!(!a.has_pending_commit());
    assert_eq!(a.epoch(), 0);
    // The honest device is still added.
    let honest = peer.call(json!({"op": "keyPackages", "name": "bob", "count": 1}));
    a.change_devices(vec![hx(&honest["packages"][0]["hex"])], vec![], now, None)
        .unwrap();
    a.merge_pending_commit().unwrap();
    assert_eq!(a.members().len(), 2);
}

#[test]
fn the_web_key_packages_follow_the_policy() {
    let Some(mut peer) = Peer::start() else {
        return;
    };
    let now = now();
    peer.call(json!({"op": "device", "name": "web", "userId": "u_web", "deviceId": "web_1"}));
    let made = peer.call(json!({"op": "keyPackages", "name": "web", "count": 1}));
    let info = check_key_package(hx(&made["packages"][0]["hex"]), now).unwrap();
    // Made by the web within the last few seconds: an hour back, 90 days on.
    let not_after = info.not_after as i64 - (now + KEY_PACKAGE_LIFETIME_SECONDS) as i64;
    assert!(not_after.abs() <= 5, "{info:?}");
    assert_eq!(
        info.not_after - info.not_before,
        KEY_PACKAGE_LIFETIME_SECONDS + KEY_PACKAGE_CLOCK_SKEW_SECONDS
    );
    // One the web made 100 days ago is refused by a native adder.
    let old = peer.call(json!({"op": "keyPackages", "name": "web", "count": 1, "nowMs": (now - 100 * 86_400) * 1000}));
    let (_, phone) = native("u_phone");
    let group = phone
        .start_group("7a6b5c4d-3e2f-4a1b-8c0d-9e8f7a6b5c4d".into(), now)
        .unwrap();
    let error = group
        .change_devices(vec![hx(&old["packages"][0]["hex"])], vec![], now, None)
        .unwrap_err();
    assert!(
        matches!(error, HubsMlsError::KeyPackageLifetime { .. }),
        "{error:?}"
    );
    assert!(!group.has_pending_commit());
    // And the fresh one is added.
    group
        .change_devices(vec![hx(&made["packages"][0]["hex"])], vec![], now, None)
        .unwrap();
}

/// The flows on the fixed interop vectors, in both directions, through the
/// `answer` and `join` commands of `tests/mls-vectors.mts`.
#[test]
fn fixed_vector_flows_both_ways() {
    if std::env::var_os("HUBS_SKIP_LIVE_TS_MLS").is_some() {
        return;
    }
    let vectors_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/mls-interop-vectors.json"
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(vectors_path).unwrap()).unwrap();
    let s = |path: &[&str]| -> String {
        let mut at = &v;
        for key in path {
            at = &at[*key];
        }
        at.as_str().unwrap().to_owned()
    };
    let b = |path: &[&str]| hex::decode(s(path)).unwrap();
    let vector_now = v["generator"]["nowSeconds"]
        .as_u64()
        .unwrap_or(1_760_000_000)
        + 600;
    let work = std::env::temp_dir().join(format!("hubs-mls-vectors-{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();
    let tool = |args: &[&str]| -> String {
        let out = node_script("mls-vectors.mts").args(args).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success(),
            "mls-vectors {args:?}: {stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        stdout
    };
    let device = |who: &str| DeviceKeys {
        user_id: s(&[who, "userId"]),
        device_id: s(&[who, "deviceId"]),
        identity_public_key: b(&[who, "identityPublicKeyHex"]),
        device_public_key: b(&[who, "devicePublicKeyHex"]),
        device_signing_key: b(&[who, "deviceSeedHex"]),
        certificate: b(&[who, "certificateHex"]),
    };
    let imported = |name: &str| {
        import_key_package(
            s(&[name, "id"]),
            b(&[name, "mlsMessageHex"]),
            b(&[name, "initPrivateKeyHex"]),
            b(&[name, "encryptionPrivateKeyHex"]),
            vector_now,
        )
        .unwrap()
    };
    let step = |kind: &str, bytes: &[u8], body: Option<&str>| match body {
        Some(body) => {
            json!({"kind": kind, "mlsMessageHex": hex::encode(bytes), "plaintextBody": body})
        }
        None => json!({"kind": kind, "mlsMessageHex": hex::encode(bytes)}),
    };

    // Forward: native Bob joins from the ts-mls welcome, opens everything,
    // replies; ts-mls Alice (her saved state) opens the replies, then adds a
    // second native phone and writes to both.
    let bob = MlsDevice::new(device("bob")).unwrap();
    let g = bob
        .join_from_welcome(
            b(&["addBob", "welcomeHex"]),
            imported("bobKeyPackage"),
            s(&["conversationId"]),
        )
        .unwrap();
    opened(g.receive(b(&["message1", "mlsMessageHex"])).unwrap());
    change_epoch(g.receive(b(&["updateCommit", "commitHex"])).unwrap());
    opened(g.receive(b(&["message2", "mlsMessageHex"])).unwrap());
    let r1 = g
        .encrypt_message(draft("m_native_1", "Hello from the native core."))
        .unwrap();
    let update = g.change_devices(vec![], vec![], vector_now, None).unwrap();
    g.merge_pending_commit().unwrap();
    let r2 = g
        .encrypt_message(draft("m_native_2", "Native, after the update."))
        .unwrap();
    let replies = work.join("native-replies.json");
    std::fs::write(
        &replies,
        json!({"steps": [
            step("message", &r1.ciphertext, Some("Hello from the native core.")),
            step("commit", &update.commit, None),
            step("message", &r2.ciphertext, Some("Native, after the update.")),
        ]})
        .to_string(),
    )
    .unwrap();
    // Bob's second phone, from his identity key in the vectors.
    let bob_identity = IdentityKeys {
        public_key: b(&["bob", "identityPublicKeyHex"]),
        signing_key: b(&["bob", "identitySeedHex"]),
    };
    let phone2 = second_device(&bob_identity, "u_bob");
    let package2 = phone2.create_key_packages(1, now()).unwrap().remove(0);
    let package_file = work.join("native-key-package.json");
    std::fs::write(
        &package_file,
        json!({"keyPackageHex": hex::encode(&package2.public_package)}).to_string(),
    )
    .unwrap();
    let added_file = work.join("ts-mls-added.json");
    let said = tool(&[
        "answer",
        vectors_path,
        replies.to_str().unwrap(),
        package_file.to_str().unwrap(),
        added_file.to_str().unwrap(),
    ]);
    assert!(
        said.contains("message ok at epoch 2: \"Hello from the native core.\""),
        "{said}"
    );
    assert!(said.contains("commit ok, now epoch 3"), "{said}");
    assert!(
        said.contains("message ok at epoch 3: \"Native, after the update.\""),
        "{said}"
    );
    let added: Value =
        serde_json::from_str(&std::fs::read_to_string(&added_file).unwrap()).unwrap();
    assert_eq!(change_epoch(g.receive(hx(&added["commitHex"])).unwrap()), 4);
    let g2 = phone2
        .join_from_welcome(hx(&added["welcomeHex"]), package2, s(&["conversationId"]))
        .unwrap();
    assert_eq!(
        opened(g.receive(hx(&added["message"]["mlsMessageHex"])).unwrap())
            .0
            .body,
        "Welcome, new phone."
    );
    assert_eq!(
        opened(g2.receive(hx(&added["message"]["mlsMessageHex"])).unwrap())
            .0
            .body,
        "Welcome, new phone."
    );

    // Reverse: native Alice makes the group with Bob's spare ts-mls key
    // package; ts-mls Bob joins (its authService checks the certificates),
    // opens everything and replies; native opens the replies.
    let alice = MlsDevice::new(device("alice")).unwrap();
    let conversation = "6a5b4c3d-2e1f-4a0b-9c8d-7e6f5a4b3c2d";
    let a = alice.start_group(conversation.into(), vector_now).unwrap();
    let change = a
        .change_devices(
            vec![b(&["bobSpareKeyPackage", "mlsMessageHex"])],
            vec![],
            vector_now,
            None,
        )
        .unwrap();
    a.merge_pending_commit().unwrap();
    let n1 = a
        .encrypt_message(draft("m_alice_1", "From native Alice."))
        .unwrap();
    let n2 = a.change_devices(vec![], vec![], vector_now, None).unwrap();
    a.merge_pending_commit().unwrap();
    let n3 = a
        .encrypt_message(draft("m_alice_2", "Native Alice, after the update."))
        .unwrap();
    let group_file = work.join("native-group.json");
    std::fs::write(
        &group_file,
        json!({
            "conversationId": conversation,
            "welcomeHex": hex::encode(change.welcome.as_ref().unwrap()),
            "steps": [
                step("message", &n1.ciphertext, Some("From native Alice.")),
                step("commit", &n2.commit, None),
                step("message", &n3.ciphertext, Some("Native Alice, after the update.")),
            ],
        })
        .to_string(),
    )
    .unwrap();
    let back_file = work.join("ts-mls-replies.json");
    let said = tool(&[
        "join",
        vectors_path,
        group_file.to_str().unwrap(),
        back_file.to_str().unwrap(),
    ]);
    assert!(said.contains("joined at epoch 1"), "{said}");
    assert!(said.contains("commit ok, now epoch 2"), "{said}");
    let back: Value = serde_json::from_str(&std::fs::read_to_string(&back_file).unwrap()).unwrap();
    let mut bodies = vec![];
    for step in back["steps"].as_array().unwrap() {
        match a.receive(hx(&step["mlsMessageHex"])).unwrap() {
            Incoming::Message { payload, .. } => bodies.push(payload.body),
            Incoming::Change { .. } => bodies.push("(commit)".into()),
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(
        bodies,
        ["Got it, from ts-mls.", "(commit)", "And after the update."]
    );
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn messages_are_padded_like_the_web() {
    let Some(mut peer) = Peer::start() else {
        return;
    };
    let now = now();
    let conversation = "5c4b3a29-1807-4f6e-8d5c-4b3a29180706";
    let (_, phone) = native("u_phone");
    // The same id lengths on both sides, so a payload's JSON has the same
    // length whichever side writes it.
    let web_device = "w".repeat(phone.device_id().len());
    peer.call(json!({"op": "device", "name": "web", "userId": "u_webxx", "deviceId": web_device}));
    peer.call(json!({"op": "start", "name": "web", "conversationId": conversation}));
    let package = phone.create_key_packages(1, now).unwrap().remove(0);
    let added = peer.call(
        json!({"op": "change", "name": "web", "add": [hex::encode(&package.public_package)]}),
    );
    let group = phone
        .join_from_welcome(hx(&added["welcome"]), package, conversation.into())
        .unwrap();

    let long = "x".repeat(1000);
    let mut sizes = vec![];
    for body in ["", "hi", long.as_str()] {
        // ts-mls opens the phone's padded message, and the TypeScript side's
        // message with the same payload size is exactly as long on the wire.
        let sent = group.encrypt_message(draft("m_1", body)).unwrap();
        web_reads(&mut peer, "web", &sent, &phone);
        let web = web_send(&mut peer, "web", "m_1", body);
        assert_eq!(
            sent.ciphertext.len(),
            hx(&web["ciphertext"]).len(),
            "body {body:?}"
        );
        assert_eq!(
            opened(group.receive(hx(&web["ciphertext"])).unwrap())
                .0
                .body,
            body
        );
        sizes.push(sent.ciphertext.len());
    }
    // Even an empty body makes a Hubs payload whose content (JSON and
    // signature) is above 256 bytes, so on both sides nothing is added and
    // two more body bytes are two more bytes on the wire. The 256-byte floor
    // shows in tests/padding-vectors.json (src/device.rs checks it).
    assert_eq!(sizes[1], sizes[0] + 2);
    assert_eq!(sizes[2], sizes[0] + 1000);
}

/// Each message's epoch, sender leaf and generation, as the core reads them
/// from the sender data, match what the web's engine reads, both ways.
/// Needs an engine with `messageHeader`; skipped with an older one.
#[test]
fn message_headers_match_the_web() {
    let Some(mut peer) = Peer::start() else {
        return;
    };
    let now = now();
    let conversation = "6a7b8c9d-0e1f-4a2b-8c3d-4e5f6a7b8c9d";
    peer.call(
        json!({"op": "device", "name": "alice", "userId": "u_alice", "deviceId": "alice_web_1"}),
    );
    peer.call(json!({"op": "start", "name": "alice", "conversationId": conversation}));
    let (_, bob) = native("u_bob");
    let package = bob.create_key_packages(1, now).unwrap().remove(0);
    let added = peer.call(
        json!({"op": "change", "name": "alice", "add": [hex::encode(&package.public_package)]}),
    );
    let b1 = bob
        .join_from_welcome(hx(&added["welcome"]), package, conversation.into())
        .unwrap();
    let web_header = |peer: &mut Peer, message: &[u8]| {
        peer.try_call(json!({"op": "header", "name": "alice", "message": hex::encode(message)}))
            .map(|reply| reply["header"].clone())
    };

    // Web to phone: three messages, headers read before opening.
    let mut sent = Vec::new();
    for index in 0..3 {
        sent.push(hx(&web_send(
            &mut peer,
            "alice",
            &format!("m_w{index}"),
            "From the web.",
        )["ciphertext"]));
    }
    let first = match web_header(&mut peer, &sent[0]) {
        Ok(header) => header,
        Err(error) => {
            eprintln!("skipping: the web engine reads no headers ({error})");
            return;
        }
    };
    assert_eq!(first, json!({"epoch": 1, "leafIndex": 0, "generation": 0}));
    for (index, message) in sent.iter().enumerate() {
        let native = b1.message_header(message.clone()).unwrap();
        let web = web_header(&mut peer, message).unwrap();
        assert_eq!(web["epoch"], native.epoch);
        assert_eq!(web["leafIndex"], native.sender_leaf_index);
        assert_eq!(web["generation"], native.generation);
        assert_eq!(native.generation, index as u32);
    }
    for message in sent.iter().rev() {
        b1.receive(message.clone()).unwrap();
    }

    // Phone to web: the web reads the phone's leaf and generations.
    for index in 0..2u32 {
        let reply = b1
            .encrypt_message(draft(&format!("m_p{index}"), "From the phone."))
            .unwrap();
        let web = web_header(&mut peer, &reply.ciphertext).unwrap();
        let native = b1.message_header(reply.ciphertext.clone()).unwrap();
        assert_eq!(native.sender_leaf_index, 1);
        assert_eq!(native.generation, index);
        assert_eq!(web["leafIndex"], native.sender_leaf_index);
        assert_eq!(web["generation"], native.generation);
        assert_eq!(web["epoch"], native.epoch);
        web_reads(&mut peer, "alice", &reply, &bob);
    }

    // A commit has no header on either side.
    let update = b1.change_devices(vec![], vec![], now, None).unwrap();
    assert_eq!(web_header(&mut peer, &update.commit).unwrap(), Value::Null);
    assert_eq!(b1.message_header(update.commit), None);
}

/// A commit with a signed removals note opens on either engine and says who
/// made it, and a key package of either engine names its device.
#[test]
fn a_note_in_a_commit_crosses_both_ways() {
    let Some(mut peer) = Peer::start() else {
        return;
    };
    let now = now();
    let (_, alice) = native("u_alice");
    let a = alice
        .start_group("a4b3c2d1-1111-4222-8333-444455556666".into(), now)
        .unwrap();
    peer.call(json!({"op": "device", "name": "bob", "userId": "u_bob", "deviceId": "bob_web_1"}));
    let made = peer.call(json!({"op": "keyPackages", "name": "bob", "count": 1}));
    let package = &made["packages"][0];
    let credential = key_package_credential(hx(&package["hex"])).unwrap();
    assert_eq!(credential.user_id, "u_bob");
    assert_eq!(credential.device_id, "bob_web_1");
    let add = a
        .change_devices(vec![hx(&package["hex"])], vec![], now, None)
        .unwrap();
    a.merge_pending_commit().unwrap();
    peer.call(json!({"op": "join", "name": "bob", "welcome": hex::encode(add.welcome.as_ref().unwrap()), "keyPackageId": package["id"]}));

    // Native to web.
    let signature = vec![7u8; 64];
    let mine = a
        .change_devices(
            vec![],
            vec![],
            now,
            Some(signed_removals_note(signature.clone())),
        )
        .unwrap();
    a.merge_pending_commit().unwrap();
    let seen =
        peer.call(json!({"op": "receive", "name": "bob", "message": hex::encode(&mine.commit)}));
    assert_eq!(hx(&seen["statement"]), signature);

    // Web to native, with the committer as the group showed it.
    let note = signed_removals_note(vec![9u8; 64]);
    let theirs = peer.call(json!({"op": "change", "name": "bob", "note": hex::encode(&note)}));
    match a.receive(hx(&theirs["commit"])).unwrap() {
        Incoming::Change {
            committer_member,
            removal_statement,
            ..
        } => {
            assert_eq!(committer_member.unwrap().device_id, "bob_web_1");
            assert_eq!(removal_statement, Some(vec![9u8; 64]));
        }
        other => panic!("expected a change, got {other:?}"),
    }

    // A plain commit carries no statement.
    let plain = peer.call(json!({"op": "change", "name": "bob"}));
    match a.receive(hx(&plain["commit"])).unwrap() {
        Incoming::Change {
            removal_statement, ..
        } => assert_eq!(removal_statement, None),
        other => panic!("expected a change, got {other:?}"),
    }
}

/// Standalone proposals and a commit closing the group for a reinit are
/// refused, and the group stays as it was and still talks.
#[test]
fn a_proposal_and_a_reinit_are_refused_and_the_group_carries_on() {
    let Some(mut peer) = Peer::start() else {
        return;
    };
    let now = now();
    let (_, alice) = native("u_alice");
    let a = alice
        .start_group("b5c4d3e2-1111-4222-8333-444455556666".into(), now)
        .unwrap();
    peer.call(json!({"op": "device", "name": "bob", "userId": "u_bob", "deviceId": "bob_web_1"}));
    let made = peer.call(json!({"op": "keyPackages", "name": "bob", "count": 1}));
    let package = &made["packages"][0];
    let add = a
        .change_devices(vec![hx(&package["hex"])], vec![], now, None)
        .unwrap();
    a.merge_pending_commit().unwrap();
    peer.call(json!({"op": "join", "name": "bob", "welcome": hex::encode(add.welcome.as_ref().unwrap()), "keyPackageId": package["id"]}));
    let leaf = a.own_leaf_index();
    let epoch = a.epoch();
    let before = a.snapshot().unwrap();

    let proposal = peer.call(json!({"op": "proposal", "name": "bob", "removeLeaf": leaf}));
    assert!(a.receive(hx(&proposal["message"])).is_err());
    let reinit = peer.call(json!({"op": "reinit", "name": "bob"}));
    assert!(a.receive(hx(&reinit["commit"])).is_err());
    assert_eq!(a.epoch(), epoch);
    assert_eq!(a.snapshot().unwrap(), before);

    let back = web_send(&mut peer, "bob", "m_1", "Still here.");
    assert_eq!(
        opened(a.receive(hx(&back["ciphertext"])).unwrap()).0.body,
        "Still here."
    );
}
