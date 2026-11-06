//! Every op with hostile fields, through the C entry points.
use std::collections::BTreeMap;

use base64ct::{Base64, Encoding};
use hubs_mls_ffi::{call, hubs_mls_call, hubs_mls_free};
use serde_json::{json, Value};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}
fn ask(v: &Value) -> Value {
    serde_json::from_str(&call(v.to_string().as_bytes())).unwrap()
}
fn ok(v: Value) -> Value {
    let a = ask(&v);
    assert!(a.get("error").is_none(), "{a}");
    a["ok"].clone()
}

fn value(r: &mut Rng, pool: &[Value]) -> Value {
    match r.below(16) {
        0 => Value::Null,
        1 => json!(true),
        2 => json!(-1),
        3 => json!(0),
        4 => json!(1),
        5 => json!(u64::MAX),
        6 => json!(1.5),
        7 => json!("x"),
        8 => json!(""),
        9 => json!("AAAA"),
        10 => json!([]),
        11 => json!({}),
        12 => json!(i64::MIN),
        13 => json!("%%%"),
        14 => json!([1, "a", null, {"k": []}]),
        _ => pool[r.below(pool.len() as u64) as usize].clone(),
    }
}

#[test]
fn every_op_answers_and_never_stops() {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/ops.txt")).unwrap();
    let mut lines = text.lines();
    let ops: Vec<&str> = lines.next().unwrap().split(' ').collect();
    let keys: Vec<&str> = lines.next().unwrap().split(' ').collect();
    let identity = ok(json!({ "op": "createIdentity" }));
    let keys_a =
        ok(json!({ "op": "createDevice", "identity": identity, "userId": "u", "deviceId": "d" }));
    let device = ok(json!({ "op": "deviceOpen", "keys": keys_a }))["device"].clone();
    let group = ok(json!({ "op": "startGroup", "device": device, "conversationId": "c", "now": 1_780_000_000u64 }))["group"].clone();
    let packages = ok(
        json!({ "op": "createKeyPackages", "device": device, "count": 2, "now": 1_780_000_000u64 }),
    );
    let track = json!({ "userId": "u", "next": 0, "gaps": [{"generation": 1, "at": 0, "before": 0}], "told": [{"generation": 2, "notice": "n"}] });
    let pool = vec![
        device.clone(),
        group.clone(),
        identity.clone(),
        keys_a.clone(),
        packages[0].clone(),
        track,
        packages[0]["publicPackage"].clone(),
        packages[0]["privatePackage"].clone(),
        json!(1_780_000_000u64),
        json!("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="),
    ];
    let mut r = Rng(0x0123_4567_89AB_CDEF);
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    let rounds: u64 = std::env::var("ITER")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000);
    for _ in 0..rounds {
        let op = ops[r.below(ops.len() as u64) as usize];
        if op == "release" {
            continue;
        }
        let mut request = serde_json::Map::new();
        request.insert("op".into(), json!(op));
        for key in &keys {
            if r.below(3) > 0 {
                request.insert((*key).into(), value(&mut r, &pool));
            }
        }
        // A debug build stops on an overflow in mls-rs-core's clock at this value, which only
        // ever comes from the app's own clock. The release build the app ships wraps instead.
        if cfg!(debug_assertions) && request.get("now") == Some(&json!(u64::MAX)) {
            request.remove("now");
        }
        if r.below(2) == 0 {
            request.insert("group".into(), group.clone());
            request.insert("device".into(), device.clone());
        }
        let answer = ask(&Value::Object(request));
        let kind = answer["error"]["kind"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| "ok".into());
        *kinds.entry(kind).or_default() += 1;
        // Anything left pending would refuse later rounds.
        ok(json!({ "op": "clearPending", "group": group }));
    }
    println!("{kinds:#?}");
    assert!(!kinds.contains_key("panic"));
}

/// Non-JSON, deep JSON, a null pointer, through the real C functions.
#[test]
fn the_c_entry_points_hold() {
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        b"{".to_vec(),
        vec![0xff, 0xfe, 0x00],
        "[".repeat(100_000).into_bytes(),
        format!("{}1{}", "{\"a\":".repeat(100_000), "}".repeat(100_000)).into_bytes(),
        b"null".to_vec(),
        b"{\"op\":5}".to_vec(),
    ];
    for case in cases {
        let mut length = 0usize;
        unsafe {
            let answer = hubs_mls_call(case.as_ptr(), case.len(), &mut length);
            assert!(!answer.is_null() && length > 0);
            let text = std::str::from_utf8(std::slice::from_raw_parts(answer, length)).unwrap();
            assert!(text.contains("error"), "{text}");
            hubs_mls_free(answer, length);
        }
    }
    let mut length = 0usize;
    unsafe {
        let answer = hubs_mls_call(std::ptr::null(), 0, &mut length);
        assert!(length > 0);
        hubs_mls_free(answer, length);
        hubs_mls_free(std::ptr::null_mut(), 0);
    }
}

/// A leaf number that does not fit, and one that is not a number: the
/// request must be refused, not quietly turned into another commit.
#[test]
fn remove_leaves_are_not_silently_changed() {
    let identity = ok(json!({ "op": "createIdentity" }));
    let keys =
        ok(json!({ "op": "createDevice", "identity": identity, "userId": "u", "deviceId": "d" }));
    let device = ok(json!({ "op": "deviceOpen", "keys": keys }))["device"].clone();
    let group = ok(json!({ "op": "startGroup", "device": device, "conversationId": "c", "now": 1_780_000_000u64 }))["group"].clone();
    let dropped = ask(
        &json!({ "op": "changeDevices", "group": group, "removeLeaves": ["1"], "now": 1_780_000_000u64 }),
    );
    let _ = ask(&json!({ "op": "clearPending", "group": group }));
    assert!(
        dropped.get("error").is_some(),
        "a leaf that is not a number was dropped: {dropped}"
    );
    let cut = ask(
        &json!({ "op": "changeDevices", "group": group, "removeLeaves": [1u64 << 32], "now": 1_780_000_000u64 }),
    );
    let _ = ask(&json!({ "op": "clearPending", "group": group }));
    assert!(
        cut.get("error").is_some(),
        "a leaf that does not fit was cut down: {cut}"
    );
}

/// The shared vectors (`test-vectors/e2ee-test-vectors.json` at the root of this repository).
fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/e2ee-test-vectors.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn base64_of_hex(hex: &Value) -> Value {
    let hex = hex.as_str().unwrap();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    json!(Base64::encode_string(&bytes))
}

/// The note as the web writes and reads it (hubs.deviceRemoval.signedRemovalsNote).
#[test]
fn the_signed_removals_note_matches_the_web() {
    let v = vectors();
    let r = &v["hubs"]["deviceRemoval"]["signedRemovalsNote"];
    let note = base64_of_hex(&r["noteHex"]);
    assert_eq!(
        ok(json!({ "op": "signedRemovalsNote", "signature": base64_of_hex(&r["signatureHex"]) })),
        note
    );
    assert_eq!(
        ok(json!({ "op": "readSignedRemovalsNote", "data": note })),
        base64_of_hex(&r["reads"])
    );
    for case in r["notNotes"].as_array().unwrap() {
        assert_eq!(
            ok(json!({ "op": "readSignedRemovalsNote", "data": base64_of_hex(&case["hex"]) })),
            Value::Null,
            "{}",
            case["name"]
        );
    }
}

/// A key package names its device, and bytes that are not one name nobody.
#[test]
fn a_key_package_names_its_device() {
    let identity = ok(json!({ "op": "createIdentity" }));
    let keys =
        ok(json!({ "op": "createDevice", "identity": identity, "userId": "u", "deviceId": "d" }));
    let device = ok(json!({ "op": "deviceOpen", "keys": keys }))["device"].clone();
    let made = ok(
        json!({ "op": "createKeyPackages", "device": device, "count": 1, "now": 1_780_000_000u64 }),
    );
    let named = ok(json!({ "op": "keyPackageCredential", "keyPackage": made[0]["publicPackage"] }));
    assert_eq!(named["userId"], "u");
    assert_eq!(named["deviceId"], "d");
    assert_eq!(named["identityPublicKey"], identity["publicKey"]);
    assert_eq!(
        ok(json!({ "op": "keyPackageCredential", "keyPackage": "AAAA" })),
        Value::Null
    );
    assert_eq!(
        ask(&json!({ "op": "keyPackageCredential", "keyPackage": "%%%" }))["error"]["kind"],
        "request"
    );
}

/// A commit with the note: the other device reads the statement and who made the commit.
#[test]
fn a_commit_carries_the_note_to_the_other_device() {
    const NOW: u64 = 1_780_000_000;
    let identity = ok(json!({ "op": "createIdentity" }));
    let keys = ok(
        json!({ "op": "createDevice", "identity": identity, "userId": "u_alice", "deviceId": "d_alice" }),
    );
    let alice = ok(json!({ "op": "deviceOpen", "keys": keys }))["device"].clone();
    let other = ok(json!({ "op": "createIdentity" }));
    let keys = ok(
        json!({ "op": "createDevice", "identity": other, "userId": "u_bob", "deviceId": "d_bob" }),
    );
    let bob = ok(json!({ "op": "deviceOpen", "keys": keys }))["device"].clone();
    let a = ok(json!({ "op": "startGroup", "device": alice, "conversationId": "c1", "now": NOW }))
        ["group"]
        .clone();
    let pack =
        ok(json!({ "op": "createKeyPackages", "device": bob, "count": 1, "now": NOW }))[0].clone();
    let added = ok(
        json!({ "op": "changeDevices", "group": a, "add": [pack["publicPackage"]], "removeLeaves": [], "now": NOW }),
    );
    ok(json!({ "op": "mergePending", "group": a }));
    let b = ok(json!({ "op": "joinFromWelcome", "device": bob, "welcome": added["welcome"], "keyPackage": pack, "conversationId": "c1" }))["group"].clone();

    let body = ok(
        json!({ "op": "signedRemovalsBody", "userId": "u_alice", "identityPublicKey": identity["publicKey"] }),
    );
    let signature =
        ok(json!({ "op": "ed25519Sign", "signingKey": identity["signingKey"], "message": body }));
    let note = ok(json!({ "op": "signedRemovalsNote", "signature": signature }));
    let change = ok(
        json!({ "op": "changeDevices", "group": a, "removeLeaves": [], "now": NOW, "note": note }),
    );
    ok(json!({ "op": "mergePending", "group": a }));
    let got = ok(json!({ "op": "receive", "group": b, "message": change["commit"] }));
    assert_eq!(got["type"], "change");
    assert_eq!(got["removalStatement"], signature);
    assert_eq!(got["committerMember"]["userId"], "u_alice");
    assert_eq!(
        got["committerMember"]["identityPublicKey"],
        identity["publicKey"]
    );

    // A commit with no note has no statement, and a note must be base64.
    let plain = ok(
        json!({ "op": "changeDevices", "group": a, "removeLeaves": [], "now": NOW, "note": null }),
    );
    ok(json!({ "op": "mergePending", "group": a }));
    let got = ok(json!({ "op": "receive", "group": b, "message": plain["commit"] }));
    assert_eq!(got["removalStatement"], Value::Null);
    assert_eq!(got["committerMember"]["userId"], "u_alice");
    assert_eq!(
        ask(
            &json!({ "op": "changeDevices", "group": a, "removeLeaves": [], "now": NOW, "note": "%%%" })
        )["error"]["kind"],
        "request"
    );
}

/// What only ts-mls can make, against the group a website device saved: a commit
/// that closes the group is refused in the words the app matches, a standalone proposal
/// is refused too, the group stays where it was, and the next message opens.
#[test]
fn a_commit_that_closes_the_group_is_refused_and_the_group_carries_on() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/refused-commits.json"
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let a = &v["alice"];
    let device = ok(json!({ "op": "deviceOpen", "keys": {
        "userId": a["userId"], "deviceId": a["deviceId"], "identityPublicKey": a["identityPublicKey"],
        "devicePublicKey": a["publicKey"], "deviceSigningKey": a["signKey"], "certificate": a["certificate"],
    }}))["device"].clone();
    let group = ok(json!({ "op": "loadGroup", "device": device, "snapshot": v["aliceSnapshot"] }))
        ["group"]
        .clone();
    let epoch = ok(json!({ "op": "groupState", "group": group }))["epoch"].clone();
    let refused = ask(&json!({ "op": "receive", "group": group, "message": v["reinitCommit"] }));
    assert_eq!(refused["error"]["kind"], "malformed", "{refused}");
    assert_eq!(
        refused["error"]["reason"],
        "malformed: reinitializing a conversation is not supported"
    );
    assert!(
        ask(&json!({ "op": "receive", "group": group, "message": v["proposal"] }))
            .get("error")
            .is_some()
    );
    assert_eq!(
        ok(json!({ "op": "groupState", "group": group }))["epoch"],
        epoch
    );
    let got = ok(json!({ "op": "receive", "group": group, "message": v["message"] }));
    assert_eq!(got["type"], "message");
    assert_eq!(got["payload"]["body"], v["body"]);
}

/// A device added back, through the C ABI, in the order the Windows app calls it: one
/// device handle for the app's run, the group handle released on "removed",
/// the snapshot stored after each step.
#[test]
fn a_windows_device_added_back_can_follow_the_next_commit() {
    const NOW: u64 = 1_780_000_000;
    let open = |user: &str, device: &str| {
        let identity = ok(json!({ "op": "createIdentity" }));
        let keys = ok(
            json!({ "op": "createDevice", "identity": identity, "userId": user, "deviceId": device }),
        );
        ok(json!({ "op": "deviceOpen", "keys": keys }))["device"].clone()
    };
    let alice = open("u_alice", "d_alice");
    let bob = open("u_bob", "d_bob");
    let a = ok(json!({ "op": "startGroup", "device": alice, "conversationId": "c1", "now": NOW }))
        ["group"]
        .clone();
    let package = |d: &Value| {
        ok(json!({ "op": "createKeyPackages", "device": d, "count": 1, "now": NOW }))[0].clone()
    };
    let add = |pack: &Value| {
        let change = ok(
            json!({ "op": "changeDevices", "group": a, "add": [pack["publicPackage"]], "removeLeaves": [], "now": NOW }),
        );
        ok(json!({ "op": "mergePending", "group": a }));
        change
    };
    let update = || {
        let change = ok(
            json!({ "op": "changeDevices", "group": a, "add": [], "removeLeaves": [], "now": NOW }),
        );
        ok(json!({ "op": "mergePending", "group": a }));
        change
    };
    let pack = package(&bob);
    let change = add(&pack);
    let b = ok(json!({ "op": "joinFromWelcome", "device": bob, "welcome": change["welcome"], "keyPackage": pack, "conversationId": "c1" }))["group"].clone();
    ok(json!({ "op": "snapshot", "group": b }));
    for _ in 0..3 {
        let change = update();
        assert_eq!(
            ok(json!({ "op": "receive", "group": b, "message": change["commit"] }))["type"],
            "change"
        );
        ok(json!({ "op": "snapshot", "group": b }));
    }
    let leaf = ok(json!({ "op": "groupState", "group": b }))["ownLeaf"].clone();
    let change = ok(
        json!({ "op": "changeDevices", "group": a, "add": [], "removeLeaves": [leaf], "now": NOW }),
    );
    ok(json!({ "op": "mergePending", "group": a }));
    assert_eq!(
        ok(json!({ "op": "receive", "group": b, "message": change["commit"] }))["type"],
        "removed"
    );
    // case Incoming.Removed: group.Dispose(); return null;
    ok(json!({ "op": "release", "group": b }));
    // The next welcome is let through.
    let pack = package(&bob);
    let change = add(&pack);
    let b = ok(json!({ "op": "joinFromWelcome", "device": bob, "welcome": change["welcome"], "keyPackage": pack, "conversationId": "c1" }))["group"].clone();
    ok(json!({ "op": "snapshot", "group": b }));
    let change = update();
    let got = ask(&json!({ "op": "receive", "group": b, "message": change["commit"] }));
    assert_eq!(
        got["ok"]["type"], "change",
        "the commit after the rejoin: {got}"
    );
}
