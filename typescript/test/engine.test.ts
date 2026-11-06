import test from "node:test";
import assert from "node:assert/strict";
import {
  createApplicationMessage,
  defaultCapabilities,
  defaultLifetime,
  encodeMlsMessage,
  generateKeyPackageWithKey,
} from "ts-mls";
import {
  type DeviceKeys,
  type PrivateDmPayload,
  PRIVATE_DM_MAX_BODY,
  changeDevices,
  ciphersuite,
  createDevice,
  createIdentity,
  createKeyPackages,
  decodeKeyPackageMessage,
  encodeKeyPackageMessage,
  encryptMessage,
  frankingCommitment,
  fromBase64,
  groupMembers,
  joinFromWelcome,
  keyPackageLifetime,
  keyPackageLifetimeOf,
  keyPackageLifetimeProblem,
  keyPackageProblem,
  keyPackagePublishProblem,
  privateDmPayloadProblem,
  readCommitment,
  readSignedRemovalsNote,
  receive,
  safetyCode,
  selfRemoveBody,
  signedRemovalsNote,
  startGroup,
  toBase64,
} from "../src/index.js";

const DAY = 86400_000;

test("encryption round trip: only group devices read it, and tampering is refused", async () => {
  const alice = await createIdentity();
  const bob = await createIdentity();
  const a1 = await createDevice(alice, "u_a", "device_a1");
  const b1 = await createDevice(bob, "u_b", "device_b1");
  const [bobPackage] = await createKeyPackages(b1, 1);
  let group = await startGroup(a1, "conversation-1");
  const added = await changeDevices(group, [bobPackage.publicPackage]);
  group = added.state;
  const bobGroup = await joinFromWelcome(added.welcome!, bobPackage);
  const sent = await encryptMessage(group, {
    v: 1,
    id: "m1",
    kind: "text",
    body: "Meet at the north gate at six.",
    sentAt: 1,
    expiresInSeconds: 3600,
    userId: "u_a",
    deviceId: "device_a1",
  });
  assert.equal(sent.ciphertext.includes("north gate"), false);
  assert.equal(
    Buffer.from(sent.ciphertext, "base64").toString("latin1").includes("north"),
    false,
  );
  // The commitment can be read without the franking key, and it matches.
  assert.equal(readCommitment(sent.ciphertext), sent.commitment);
  const opened = await receive(bobGroup, sent.ciphertext);
  assert.equal(opened.kind, "message");
  if (opened.kind !== "message") return;
  assert.equal(opened.payload.body, "Meet at the north gate at six.");
  assert.equal(opened.sender.userId, "u_a");
  assert.equal(opened.sender.deviceId, "device_a1");
  // One flipped byte and the message does not open.
  const bytes = Buffer.from(sent.ciphertext, "base64");
  bytes[bytes.length - 5] ^= 1;
  await assert.rejects(receive(bobGroup, bytes.toString("base64")));
  // A device whose certificate was not signed by the identity it names is refused.
  const mallory = await createDevice(await createIdentity(), "u_b", "evil");
  const [forged] = await createKeyPackages(
    { ...mallory, identityPublicKey: bob.publicKey },
    1,
  );
  await assert.rejects(changeDevices(group, [forged.publicPackage]));
});

test("safety codes match on both sides and change with a new identity key", async () => {
  const alice = await createIdentity();
  const bob = await createIdentity();
  const a = { userId: "u_a", identityPublicKey: alice.publicKey };
  const b = { userId: "u_b", identityPublicKey: bob.publicKey };
  const code = await safetyCode(a, b);
  assert.match(code, /^(\d{5} ){11}\d{5}$/);
  assert.equal(await safetyCode(b, a), code);
  const bobAgain = await createIdentity();
  assert.notEqual(
    await safetyCode(a, { ...b, identityPublicKey: bobAgain.publicKey }),
    code,
  );
});

test("the self-removal test vector verifies", async () => {
  const cs = await ciphersuite();
  const body = selfRemoveBody(
    "00000000-0000-4000-8000-000000000001",
    "device-test-vector-01",
    1793232000000,
  );
  assert.equal(
    Buffer.from(body).toString("hex"),
    "68756273207072697661746520646d732073656c662d72656d6f76652076310030303030303030302d303030302d343030302d383030302d303030303030303030303031006465766963652d746573742d766563746f722d30310031373933323332303030303030",
  );
  const publicKey = fromBase64("e366vgtCEeAb5UKFqqdlJpd2rLzyIFLnmI/gC93GhYE=");
  const proof = fromBase64(
    "TT5wxy8ScjrVs6nhVPwbbcmZAluaucKoOawclAlnGJX6LeiaS3g7S4X50VUrjJezObftszWtPChYPo+81zfqBA==",
  );
  assert.equal(await cs.signature.verify(publicKey, body, proof), true);
  // Ed25519 signatures are deterministic, so the test key signs to the same proof.
  const signKey = fromBase64(
    "MC4CAQAwBQYDK2VwBCIEIAxJIBrJGs3reqQmo4WJr7p9+SJnjgW91m8eryETSi3r",
  );
  assert.equal(
    toBase64(await cs.signature.sign(signKey, body)),
    toBase64(proof),
  );
});

/** A key package with the ts-mls default lifetime, which never expires. */
async function neverExpiringKeyPackage(device: DeviceKeys) {
  const made = await generateKeyPackageWithKey(
    {
      credentialType: "basic",
      identity: new TextEncoder().encode(
        JSON.stringify({
          v: 1,
          userId: device.userId,
          deviceId: device.deviceId,
          identityPublicKey: device.identityPublicKey,
          certificate: device.certificate,
        }),
      ),
    },
    defaultCapabilities(),
    defaultLifetime,
    [],
    {
      publicKey: fromBase64(device.publicKey),
      signKey: fromBase64(device.signKey),
    },
    await ciphersuite(),
  );
  return encodeKeyPackageMessage(made.publicPackage);
}

test("key packages: valid for 90 days, and one that never expires or has expired is refused", async () => {
  const now = Date.now();
  const device = await createDevice(
    await createIdentity(),
    "u_kp",
    "device_kp1",
  );
  const [made] = await createKeyPackages(device, 1, now);
  const lifetime = keyPackageLifetimeOf(
    decodeKeyPackageMessage(made.publicPackage),
  )!;
  const seconds = BigInt(Math.floor(now / 1000));
  assert.equal(lifetime.notBefore, seconds - 3600n);
  assert.equal(lifetime.notAfter, seconds + 90n * 86400n);
  assert.deepEqual(lifetime, keyPackageLifetime(now));
  assert.equal(made.createdAt, now);
  assert.equal(made.expiresAt, Number(lifetime.notAfter) * 1000);
  // Usable until the 90 days are up.
  assert.equal(keyPackageProblem(made.publicPackage, now), null);
  assert.equal(keyPackageProblem(made.publicPackage, now + 89 * DAY), null);
  assert.match(
    keyPackageProblem(made.publicPackage, now + 91 * DAY)!,
    /expired/,
  );
  // An hour of clock skew either way, no more.
  assert.equal(keyPackageProblem(made.publicPackage, now - 3599_000), null);
  assert.match(
    keyPackageProblem(made.publicPackage, now - 2 * 3600_000 - 2000)!,
    /not valid yet/,
  );
  // A key package that never expires is refused.
  const legacy = await neverExpiringKeyPackage(device);
  assert.match(keyPackageProblem(legacy, now)!, /longer than 90 days/);
  assert.match(
    keyPackageLifetimeProblem(
      { notBefore: 0n, notAfter: 2n ** 63n - 1n },
      now,
    )!,
    /longer than 90 days/,
  );
  // The server stores only key packages with 60 days or more left.
  assert.equal(keyPackagePublishProblem(lifetime, now + 29 * DAY), null);
  assert.match(
    keyPackagePublishProblem(lifetime, now + 31 * DAY)!,
    /too long ago/,
  );
  // A group's own first leaf gets the same lifetime.
  const group = await startGroup(device, "conversation-kp", now);
  const leaf = group.ratchetTree.find((node) => node?.nodeType === "leaf");
  assert.ok(
    leaf?.nodeType === "leaf" && leaf.leaf.leafNodeSource === "key_package",
  );
  if (leaf?.nodeType === "leaf" && leaf.leaf.leafNodeSource === "key_package")
    assert.equal(leaf.leaf.lifetime.notAfter, lifetime.notAfter);
});

test("payload rules are the same everywhere, and a device refuses a payload that breaks them", async () => {
  const good = {
    v: 1,
    id: "m_0001",
    kind: "text",
    body: "Meet at the north gate at six.",
    sentAt: 1760000000000,
    expiresInSeconds: 604800,
    userId: "u_a",
    deviceId: "device_a1",
    frankingKey: Buffer.alloc(32, 17).toString("base64"),
  };
  assert.equal(privateDmPayloadProblem(good), null);
  for (const bad of [
    { ...good, kind: "notice" },
    { ...good, id: "notice:u_b:key" },
    { ...good, kind: "timer" },
    { ...good, expiresInSeconds: 12345 },
    { ...good, sentAt: 1.5 },
    { ...good, body: "x".repeat(PRIVATE_DM_MAX_BODY + 1) },
    { ...good, body: "lone \ud800 surrogate" },
    { ...good, frankingKey: "" },
    { ...good, frankingKey: Buffer.alloc(80, 1).toString("base64") },
    { ...good, extra: "not covered by the commitment" },
    { ...good, v: 2 },
  ])
    assert.notEqual(privateDmPayloadProblem(bad), null, JSON.stringify(bad));

  // A sender that builds its own payload (here a fake system notice, with a
  // matching commitment) is refused by the receiving device.
  const a1 = await createDevice(await createIdentity(), "u_a", "device_a1");
  const b1 = await createDevice(await createIdentity(), "u_b", "device_b1");
  const [bobPackage] = await createKeyPackages(b1, 1);
  const added = await changeDevices(await startGroup(a1, "conversation-1"), [
    bobPackage.publicPackage,
  ]);
  const bobGroup = await joinFromWelcome(added.welcome!, bobPackage);
  const fake = {
    ...good,
    kind: "notice",
    body: "Safety codes verified.",
    userId: "u_a",
    deviceId: "device_a1",
  } as unknown as PrivateDmPayload;
  const commitment = await frankingCommitment(
    fromBase64(fake.frankingKey),
    fake,
  );
  const made = await createApplicationMessage(
    added.state,
    new TextEncoder().encode(JSON.stringify(fake)),
    await ciphersuite(),
    commitment,
  );
  const ciphertext = Buffer.from(
    encodeMlsMessage({
      privateMessage: made.privateMessage,
      wireformat: "mls_private_message",
      version: "mls10",
    }),
  ).toString("base64");
  await assert.rejects(receive(bobGroup, ciphertext), /Messages are text/);
  // A refused message leaves Bob's state whole, so Alice's next message
  // still opens. Wiping the consumed secrets before the checks passed would
  // also wipe keys the kept state still needs.
  const mismatched = await createApplicationMessage(
    made.newState,
    new TextEncoder().encode(JSON.stringify(good)),
    await ciphersuite(),
    new Uint8Array(32),
  );
  await assert.rejects(
    receive(
      bobGroup,
      Buffer.from(
        encodeMlsMessage({
          privateMessage: mismatched.privateMessage,
          wireformat: "mls_private_message",
          version: "mls10",
        }),
      ).toString("base64"),
    ),
    /did not match its commitment/,
  );
  const next = await encryptMessage(mismatched.newState, {
    v: 1,
    id: "m_0002",
    kind: "text",
    body: "Still readable.",
    sentAt: 2,
    expiresInSeconds: 3600,
    userId: "u_a",
    deviceId: "device_a1",
  });
  const opened = await receive(bobGroup, next.ciphertext);
  assert.equal(
    opened.kind === "message" && opened.payload.body,
    "Still readable.",
  );
});

test("a commit's note reaches the other device, and other data reads as no note", async () => {
  const alice = await createIdentity();
  const bob = await createIdentity();
  const a1 = await createDevice(alice, "u_a", "device_a1");
  const b1 = await createDevice(bob, "u_b", "device_b1");
  const [bobPackage] = await createKeyPackages(b1, 1);
  const added = await changeDevices(await startGroup(a1, "conversation-note"), [
    bobPackage.publicPackage,
  ]);
  const bobGroup = await joinFromWelcome(added.welcome!, bobPackage);
  const signature = new Uint8Array(64).fill(7);
  const plain = await changeDevices(added.state, []);
  const plainResult = await receive(bobGroup, plain.commit);
  assert.equal(plainResult.kind, "change");
  assert.equal(
    plainResult.kind === "change" && plainResult.removalStatement,
    null,
  );

  const noted = await changeDevices(
    plain.state,
    [],
    [],
    signedRemovalsNote(signature),
  );
  assert.ok(plainResult.kind === "change");
  const result = await receive(plainResult.state, noted.commit);
  assert.ok(result.kind === "change");
  assert.deepEqual(result.removalStatement, signature);
  assert.equal(result.sender?.deviceId, "device_a1");

  assert.equal(readSignedRemovalsNote(new Uint8Array(0)), null);
  assert.equal(readSignedRemovalsNote(new Uint8Array(32)), null);
  assert.equal(
    readSignedRemovalsNote(signedRemovalsNote(signature).subarray(0, 100)),
    null,
  );
});

test("a message from a device removed before it arrived stays refused, so a removed device cannot keep talking through old keys", async () => {
  const alice = await createIdentity();
  const bob = await createIdentity();
  const a1 = await createDevice(alice, "u_a", "device_a1");
  const a2 = await createDevice(alice, "u_a", "device_a2");
  const b1 = await createDevice(bob, "u_b", "device_b1");
  const [a2Package] = await createKeyPackages(a2, 1);
  const [bobPackage] = await createKeyPackages(b1, 1);
  const added = await changeDevices(await startGroup(a1, "conversation-late"), [
    a2Package.publicPackage,
    bobPackage.publicPackage,
  ]);
  const a2Group = await joinFromWelcome(added.welcome!, a2Package);
  const bobGroup = await joinFromWelcome(added.welcome!, bobPackage);
  const late = await encryptMessage(a2Group, {
    v: 1,
    id: "late",
    kind: "text",
    body: "sent after the removal, in the old epoch",
    sentAt: 1,
    expiresInSeconds: 3600,
    userId: "u_a",
    deviceId: "device_a2",
  });
  const removal = await changeDevices(
    added.state,
    [],
    [groupMembers(added.state).find((m) => m.deviceId === "device_a2")!.leafIndex],
  );
  const after = await receive(bobGroup, removal.commit);
  assert.ok(after.kind === "change");
  after.release();
  await assert.rejects(
    receive(after.state, late.ciphertext),
    /did not come from the device it names/,
  );
});
